use std::fmt;
use std::io::{Read, Write};
use std::iter;
use std::iter::Iterator;
use std::net::{Ipv4Addr, Ipv6Addr, IpAddr};
use std::slice;
use std::vec;

use packet::result::{Result, Error};
use packet::util::{be_u16, be_u32, set_be_u16, Pair, Checksum};

#[derive(Copy, Clone, PartialEq)]
pub enum IpProto {
    HopByHopOpts,
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
            0 => IpProto::HopByHopOpts,
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
            IpProto::HopByHopOpts => 0,
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
            IpProto::HopByHopOpts => write!(f, "Hop-by-Hop Options"),
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
pub struct Ipv4Header<'a> {
    buf: &'a [u8],
}

impl<'a> Ipv4Header<'a> {
    pub fn with_buf(buf: &[u8]) -> Ipv4Header {
        Ipv4Header { buf: buf }
    }

    pub fn max_len() -> usize {
        60
    }

    pub fn len(&self) -> usize {
        ((self.buf[0] & 0xF) * 4) as usize
    }

    pub fn src(&self) -> Ipv4Addr {
        let mut src = [0; 4];
        (&self.buf[12..]).read_exact(&mut src).unwrap();
        Ipv4Addr::from(src)
    }

    pub fn dest(&self) -> Ipv4Addr {
        let mut dest = [0; 4];
        (&self.buf[16..]).read_exact(&mut dest).unwrap();
        Ipv4Addr::from(dest)
    }

    pub fn total_len(&self) -> usize {
        be_u16(&self.buf[2..]) as usize
    }

    pub fn next(&self) -> IpProto {
        IpProto::new(self.buf[9])
    }

    pub fn pseudo_iter
        (&self,
         len: usize)
         -> iter::Chain<iter::Map<slice::Chunks<'a, u8>, fn(&[u8]) -> u16>, vec::IntoIter<u16>> {
        let pseudo = vec![self.next().value() as u16, len as u16];
        self.buf[12..20]
            .pair_iter()
            .chain(pseudo.into_iter())
    }

    fn checksum(&self) -> u16 {
        be_u16(&self.buf[10..])
    }

    pub fn checksum_valid(&self) -> bool {
        (self.checksum() ==
         self.buf[..10]
            .pair_iter()
            .chain(self.buf[12..self.len()].pair_iter())
            .checksum())
    }
}

#[derive(Debug)]
pub struct Ipv4HeaderMut<'a> {
    buf: &'a mut [u8],
}

impl<'a> Ipv4HeaderMut<'a> {
    pub fn new(buf: &mut [u8]) -> Ipv4HeaderMut {
        buf[0] = 4 << 4 | 5;
        let mut header = Ipv4HeaderMut::with_buf(buf);
        header.set_ttl(64);
        header
    }

    pub fn with_buf(buf: &mut [u8]) -> Ipv4HeaderMut {
        Ipv4HeaderMut { buf: buf }
    }

    pub fn set_ttl(&mut self, ttl: u8) {
        self.buf[8] = ttl;
    }

    pub fn set_src(&mut self, addr: Ipv4Addr) {
        (&mut self.buf[12..]).write_all(&addr.octets()).unwrap();
    }

    pub fn set_dest(&mut self, addr: Ipv4Addr) {
        (&mut self.buf[16..]).write_all(&addr.octets()).unwrap();
    }

    pub fn set_total_len(&mut self, len: usize) {
        set_be_u16(&mut self.buf[2..], len as u16);
    }

    pub fn set_next(&mut self, proto: IpProto) {
        self.buf[9] = proto.value();
    }

    fn set_checksum(&mut self, checksum: u16) {
        set_be_u16(&mut self.buf[10..], checksum);
    }

    pub fn calculate_checksum(&mut self) {
        let checksum = {
            let ip_hdr = Ipv4Header::with_buf(self.buf);
            let pre = &self.buf[..10];
            let post = &self.buf[12..ip_hdr.len()];
            pre.pair_iter().chain(post.pair_iter()).checksum()
        };
        self.set_checksum(checksum);
    }
}

#[derive(Debug)]
pub struct Ipv6Header<'a> {
    buf: &'a [u8],
}

impl<'a> Ipv6Header<'a> {
    pub fn with_buf(buf: &[u8]) -> Ipv6Header {
        Ipv6Header { buf: buf }
    }

    pub fn len() -> usize {
        40
    }

    pub fn src(&self) -> Ipv6Addr {
        unimplemented!();
    }

    pub fn dest(&self) -> Ipv6Addr {
        unimplemented!();
    }

    pub fn total_len(&self) -> usize {
        unimplemented!();
    }

    pub fn next(&self) -> IpProto {
        unimplemented!();
    }

    fn pseudo_iter
        (&self,
         len: usize)
         -> iter::Chain<iter::Map<slice::Chunks<'a, u8>, fn(&[u8]) -> u16>, vec::IntoIter<u16>> {
        let pseudo = vec![self.next().value() as u16, len as u16];
        self.buf[8..40]
            .pair_iter()
            .chain(pseudo.into_iter())
    }
}

#[derive(Debug)]
pub struct Ipv6HeaderMut<'a> {
    buf: &'a mut [u8],
}

impl<'a> Ipv6HeaderMut<'a> {
    pub fn with_buf(buf: &mut [u8]) -> Ipv6HeaderMut {
        Ipv6HeaderMut { buf: buf }
    }

    pub fn new(buf: &mut [u8]) -> Ipv6HeaderMut {
        buf[0] = 6 << 4;
        Ipv6HeaderMut::with_buf(buf)
    }

    pub fn set_src(&mut self, _addr: Ipv6Addr) {
        unimplemented!();
    }

    pub fn set_dest(&mut self, _addr: Ipv6Addr) {
        unimplemented!();
    }

    pub fn set_total_len(&mut self, _len: usize) {
        unimplemented!();
    }

    pub fn set_next(&mut self, _proto: IpProto) {
        unimplemented!();
    }
}

#[derive(Debug)]
pub enum IpHeader<'a> {
    V4(Ipv4Header<'a>),
    V6(Ipv6Header<'a>),
}

impl<'a> IpHeader<'a> {
    pub fn with_buf(buf: &'a [u8]) -> Result<IpHeader<'a>> {
        match buf[0] >> 4 {
            4 => Ok(IpHeader::V4(Ipv4Header::with_buf(buf))),
            6 => Ok(IpHeader::V6(Ipv6Header::with_buf(buf))),
            v => Err(Error::IPVersionNotSupported(v)),
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
            IpHeader::V6(ref _h) => Ipv6Header::len(),
        }
    }

    pub fn total_len(&self) -> usize {
        match *self {
            IpHeader::V4(ref h) => h.total_len(),
            IpHeader::V6(ref h) => h.total_len(),
        }
    }

    pub fn pseudo_iter
        (&self,
         len: usize)
         -> iter::Chain<iter::Map<slice::Chunks<'a, u8>, fn(&[u8]) -> u16>, vec::IntoIter<u16>> {
        match *self {
            IpHeader::V4(ref h) => h.pseudo_iter(len),
            IpHeader::V6(ref h) => h.pseudo_iter(len),
        }
    }

    pub fn next(&self) -> IpProto {
        match *self {
            IpHeader::V4(ref h) => h.next(),
            IpHeader::V6(ref h) => h.next(),
        }
    }
}

#[derive(Debug)]
pub enum IpHeaderMut<'a> {
    V4(Ipv4HeaderMut<'a>),
    V6(Ipv6HeaderMut<'a>),
}

impl<'a> IpHeaderMut<'a> {
    pub fn new(buf: &mut [u8], addr: IpAddr) -> IpHeaderMut {
        match addr {
            IpAddr::V4(ref _a) => IpHeaderMut::V4(Ipv4HeaderMut::new(buf)),
            IpAddr::V6(ref _a) => IpHeaderMut::V6(Ipv6HeaderMut::new(buf)),
        }
    }

    pub fn with_buf(buf: &mut [u8]) -> Result<IpHeaderMut> {
        match buf[0] >> 4 {
            4 => Ok(IpHeaderMut::V4(Ipv4HeaderMut::with_buf(buf))),
            6 => Ok(IpHeaderMut::V6(Ipv6HeaderMut::with_buf(buf))),
            v => Err(Error::IPVersionNotSupported(v)),
        }
    }

    pub fn set_src(&mut self, addr: IpAddr) {
        match *self {
            IpHeaderMut::V4(ref mut h) => {
                match addr {
                    IpAddr::V4(a) => h.set_src(a),
                    IpAddr::V6(_a) => panic!("Cannot set an IPv6 address on an IPv4 header"),
                }
            }
            IpHeaderMut::V6(ref mut h) => {
                match addr {
                    IpAddr::V4(_a) => panic!("Cannot set an IPv4 address on an IPv6 header"),
                    IpAddr::V6(a) => h.set_src(a),
                }
            }
        }
    }

    pub fn set_dest(&mut self, addr: IpAddr) {
        match *self {
            IpHeaderMut::V4(ref mut h) => {
                match addr {
                    IpAddr::V4(a) => h.set_dest(a),
                    IpAddr::V6(_a) => panic!("Cannot set an IPv6 address on an IPv4 header"),
                }
            }
            IpHeaderMut::V6(ref mut h) => {
                match addr {
                    IpAddr::V4(_a) => panic!("Cannot set an IPv4 address on an IPv6 header"),
                    IpAddr::V6(a) => h.set_dest(a),
                }
            }
        }
    }

    pub fn set_total_len(&mut self, len: usize) {
        match *self {
            IpHeaderMut::V4(ref mut h) => h.set_total_len(len),
            IpHeaderMut::V6(ref mut h) => h.set_total_len(len),
        }
    }

    pub fn calculate_checksum(&mut self) {
        match *self {
            IpHeaderMut::V4(ref mut h) => h.calculate_checksum(),
            IpHeaderMut::V6(ref mut _h) => (),
        }
    }

    pub fn set_next(&mut self, proto: IpProto) {
        match *self {
            IpHeaderMut::V4(ref mut h) => h.set_next(proto),
            IpHeaderMut::V6(ref mut h) => h.set_next(proto),
        }
    }
}

#[derive(Debug)]
pub struct HopByHopOpts<'a> {
    buf: &'a [u8],
}

impl<'a> HopByHopOpts<'a> {
    pub fn with_buf(buf: &[u8]) -> HopByHopOpts {
        HopByHopOpts { buf: buf }
    }

    pub fn len(&self) -> usize {
        (self.buf[1] * 8) as usize
    }

    pub fn next(&self) -> IpProto {
        IpProto::new(self.buf[0])
    }
}

#[derive(Debug)]
pub enum ExtHeader<'a> {
    HopByHop(HopByHopOpts<'a>),
}

impl<'a> ExtHeader<'a> {
    pub fn with_buf(buf: &[u8], proto: IpProto) -> Result<ExtHeader> {
        match proto {
            IpProto::HopByHopOpts => Ok(ExtHeader::HopByHop(HopByHopOpts::with_buf(buf))),
            p => Err(Error::IPProtoNotSupported(p)),
        }
    }

    pub fn next(&self) -> IpProto {
        match *self {
            ExtHeader::HopByHop(ref h) => h.next(),
        }
    }

    pub fn len(&self) -> usize {
        match *self {
            ExtHeader::HopByHop(ref h) => h.len(),
        }
    }
}
