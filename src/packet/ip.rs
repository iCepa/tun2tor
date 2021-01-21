#![allow(dead_code)]

use std::fmt;
use std::io::{self, Read, Write};
use std::iter;
use std::iter::Iterator;
use std::net::{Ipv4Addr, Ipv6Addr, IpAddr};
use std::vec;

use byteorder::NetworkEndian;

use packet::bytes::{self, Bytes, Checksum};

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

pub struct Ipv4Header(Bytes);

impl Ipv4Header {
    pub fn with_bytes(bytes: Bytes) -> io::Result<(Ipv4Header, Bytes)> {
        let mut header = Ipv4Header(bytes);
        let len = header.len();
        let remaining = try_split!(header.0, len);
        Ok((header, remaining))
    }

    pub fn len(&self) -> usize {
        ((self.0.read_u8(0).unwrap() & 0xF) * 4) as usize
    }

    pub fn src(&self) -> Ipv4Addr {
        let mut src = [0; 4];
        (&self.0.as_slice()[12..]).read_exact(&mut src).unwrap();
        Ipv4Addr::from(src)
    }

    pub fn dest(&self) -> Ipv4Addr {
        let mut dest = [0; 4];
        (&self.0.as_slice()[16..]).read_exact(&mut dest).unwrap();
        Ipv4Addr::from(dest)
    }

    pub fn total_len(&self) -> usize {
        self.0.read_u16::<NetworkEndian>(2).unwrap() as usize
    }

    pub fn next(&self) -> IpProto {
        IpProto::new(self.0.read_u8(9).unwrap())
    }

    pub fn pseudo_iter(&self, len: usize) -> iter::Chain<bytes::PairIter, vec::IntoIter<u16>> {
        let pseudo = vec![self.next().value() as u16, len as u16];
        self.0.slice(12, 20).pair_iter().chain(pseudo.into_iter())
    }

    fn checksum(&self) -> u16 {
        self.0.read_u16::<NetworkEndian>(10).unwrap()
    }

    fn calculated_checksum(&self) -> u16 {
        self.0
            .slice(0, 10)
            .pair_iter()
            .chain(self.0.slice(12, self.len()).pair_iter())
            .checksum()
    }

    pub fn checksum_valid(&self) -> bool {
        self.checksum() == self.calculated_checksum()
    }

    pub fn set_ttl(&mut self, ttl: u8) {
        self.0.write_u8(8, ttl).unwrap();
    }

    pub fn set_src(&mut self, addr: Ipv4Addr) {
        (&mut self.0.as_mut()[12..])
            .write_all(&addr.octets())
            .unwrap();
    }

    pub fn set_dest(&mut self, addr: Ipv4Addr) {
        (&mut self.0.as_mut()[16..])
            .write_all(&addr.octets())
            .unwrap();
    }

    pub fn set_total_len(&mut self, len: usize) {
        self.0.write_u16::<NetworkEndian>(2, len as u16).unwrap();
    }

    pub fn set_next(&mut self, proto: IpProto) {
        self.0.write_u8(9, proto.value()).unwrap();
    }

    fn set_checksum(&mut self, checksum: u16) {
        self.0.write_u16::<NetworkEndian>(10, checksum).unwrap();
    }

    pub fn calculate_checksum(&mut self) {
        let checksum = self.calculated_checksum();
        self.set_checksum(checksum);
    }
}

impl fmt::Debug for Ipv4Header {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt.debug_struct("Ipv4Header")
            .field("src", &self.src())
            .field("dest", &self.dest())
            .field("total_len", &self.total_len())
            .field("next", &self.next())
            .field("checksum_valid", &self.checksum_valid())
            .finish()
    }
}

pub struct Ipv6Header(Bytes);

impl Ipv6Header {
    pub fn with_bytes(bytes: Bytes) -> io::Result<(Ipv6Header, Bytes)> {
        let mut header = Ipv6Header(bytes);
        if let Some(payload_len) = header.payload_len() {
            try_split!(header.0, Ipv6Header::len() + payload_len);
        }
        let remaining = try_split!(header.0, Ipv6Header::len());
        Ok((header, remaining))
    }

    pub fn len() -> usize {
        40
    }

    pub fn src(&self) -> Ipv6Addr {
        let mut src = [0; 16];
        (&self.0.as_slice()[8..]).read_exact(&mut src).unwrap();
        Ipv6Addr::from(src)
    }

    pub fn dest(&self) -> Ipv6Addr {
        let mut dest = [0; 16];
        (&self.0.as_slice()[24..]).read_exact(&mut dest).unwrap();
        Ipv6Addr::from(dest)
    }

    pub fn payload_len(&self) -> Option<usize> {
        let payload_len = self.0.read_u16::<NetworkEndian>(4).unwrap();
        if payload_len > 0 {
            Some(payload_len as usize)
        } else {
            None
        }
    }

    pub fn next(&self) -> IpProto {
        IpProto::new(self.0.read_u8(6).unwrap())
    }

    fn pseudo_iter(&self, len: usize) -> iter::Chain<bytes::PairIter, vec::IntoIter<u16>> {
        let pseudo = vec![self.next().value() as u16, len as u16];
        self.0.slice(8, 40).pair_iter().chain(pseudo.into_iter())
    }
}

impl fmt::Debug for Ipv6Header {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt.debug_struct("Ipv6Header")
            .field("src", &self.src())
            .field("dest", &self.dest())
            .field("payload_len", &self.payload_len())
            .field("next", &self.next())
            .finish()
    }
}

#[derive(Debug)]
pub enum IpHeader {
    V4(Ipv4Header),
    V6(Ipv6Header),
}

impl IpHeader {
    pub fn with_bytes(bytes: Bytes) -> io::Result<(IpHeader, Bytes)> {
        match bytes.read_u8(0).map(|v| v >> 4) {
            Ok(4) => Ipv4Header::with_bytes(bytes).map(|(h, b)| (IpHeader::V4(h), b)),
            Ok(6) => Ipv6Header::with_bytes(bytes).map(|(h, b)| (IpHeader::V6(h), b)),
            Ok(..) => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "IP version not supported",
            )),
            Err(e) => Err(e.into()),
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
            IpHeader::V6(..) => Ipv6Header::len(),
        }
    }

    pub fn total_len(&self) -> Option<usize> {
        match *self {
            IpHeader::V4(ref h) => Some(h.total_len()),
            IpHeader::V6(ref h) => h.payload_len().map(|l| l + Ipv6Header::len()),
        }
    }

    pub fn pseudo_iter(&self, len: usize) -> iter::Chain<bytes::PairIter, vec::IntoIter<u16>> {
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

    pub fn set_total_len(&mut self, len: usize) {
        match *self {
            IpHeader::V4(ref mut h) => h.set_total_len(len),
            IpHeader::V6(ref _h) => unimplemented!(),
        }
    }

    pub fn set_next(&mut self, proto: IpProto) {
        match *self {
            IpHeader::V4(ref mut h) => h.set_next(proto),
            IpHeader::V6(ref _h) => unimplemented!(),
        }
    }
}

#[derive(Default, Debug, Clone)]
pub struct IpHeaderBuilder {
    src: Option<IpAddr>,
    dest: Option<IpAddr>,
    proto: Option<IpProto>,
    ttl: Option<u8>,
}

impl IpHeaderBuilder {
    pub fn src(mut self, src: IpAddr) -> IpHeaderBuilder {
        self.src = Some(src);
        self
    }

    pub fn dest(mut self, dest: IpAddr) -> IpHeaderBuilder {
        self.dest = Some(dest);
        self
    }

    pub fn proto(mut self, proto: IpProto) -> IpHeaderBuilder {
        self.proto = Some(proto);
        self
    }

    pub fn len(&self) -> Option<usize> {
        match self.src {
            Some(IpAddr::V4(..)) => Some(20),
            Some(IpAddr::V6(..)) => Some(Ipv6Header::len()),
            None => None,
        }
    }

    pub fn build(self, mut bytes: Bytes) -> (IpHeader, Bytes) {
        let src = match self.src {
            Some(IpAddr::V4(a)) => a,
            _ => unimplemented!(),
        };

        let dest = match self.dest {
            Some(IpAddr::V4(a)) => a,
            _ => unimplemented!(),
        };

        let proto = self.proto.unwrap_or_else(|| unimplemented!());
        let ttl = self.ttl.unwrap_or(64);

        bytes.as_mut()[0] = 4 << 4 | 5;
        let (mut header, remaining) = Ipv4Header::with_bytes(bytes).unwrap();
        header.set_src(src);
        header.set_dest(dest);
        header.set_next(proto);
        header.set_ttl(ttl);
        (IpHeader::V4(header), remaining)
    }
}

#[derive(Debug)]
pub struct HopByHopOpts(Bytes);

impl HopByHopOpts {
    pub fn with_bytes(bytes: Bytes) -> io::Result<(HopByHopOpts, Bytes)> {
        let mut opts = HopByHopOpts(bytes);
        let len = opts.len();
        let remaining = try_split!(opts.0, len);
        Ok((opts, remaining))
    }

    pub fn len(&self) -> usize {
        (self.0.read_u8(1).unwrap() * 8) as usize
    }

    pub fn next(&self) -> IpProto {
        IpProto::new(self.0.read_u8(0).unwrap())
    }
}

#[derive(Debug)]
pub enum ExtHeader {
    HopByHop(HopByHopOpts),
}

impl ExtHeader {
    pub fn with_bytes(bytes: Bytes, proto: IpProto) -> io::Result<(ExtHeader, Bytes)> {
        match proto {
            IpProto::HopByHopOpts => {
                HopByHopOpts::with_bytes(bytes).map(|(h, b)| (ExtHeader::HopByHop(h), b))
            }
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "IP proto not supported",
            )),
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
