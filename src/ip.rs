use std::fmt;
use std::mem;
use std::result;
use std::convert::From;
use std::io::Cursor;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::iter::Iterator;

use byteorder;
use byteorder::{LittleEndian, BigEndian, ReadBytesExt};

pub enum Error {
    ByteOrder(byteorder::Error),
    UnsupportedVersion(u8)
}

impl From<byteorder::Error> for Error {
    fn from(error: byteorder::Error) -> Error {
        Error::ByteOrder(error)
    }
}

impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            &Error::ByteOrder(ref error) => error.fmt(f),
            &Error::UnsupportedVersion(version) => write!(f, "Unsupported IP version {:?}", version),
        }
    }
}

pub type Result<T> = result::Result<T, Error>;

pub trait FromBytes {
    fn from_bytes(bytes: &[u8]) -> Result<Self>;
}

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
    fn value(&self) -> u8 {
        match self {
            &IpProto::Icmp => 1,
            &IpProto::Igmp => 2,
            &IpProto::Udp => 17,
            &IpProto::UdpLite => 136,
            &IpProto::Tcp => 6,
            &IpProto::Unknown(value) => value,
        }
    }
}

impl fmt::Debug for IpProto {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            &IpProto::Icmp => write!(f, "ICMP"),
            &IpProto::Igmp => write!(f, "IGMP"),
            &IpProto::Udp => write!(f, "UDP"),
            &IpProto::UdpLite => write!(f, "UDPLite"),
            &IpProto::Tcp => write!(f, "TCP"),
            &IpProto::Unknown(value) => write!(f, "Unknown ({})", value),
        }
    }
}

impl FromBytes for Ipv4Addr {
    fn from_bytes(addr: &[u8]) -> Result<Ipv4Addr> {
        let mut rdr = Cursor::new(addr);
        let a = try!(rdr.read_u8());
        let b = try!(rdr.read_u8());
        let c = try!(rdr.read_u8());
        let d = try!(rdr.read_u8());
        Ok(Ipv4Addr::new(a, b, c, d))
    }
}

impl FromBytes for Ipv6Addr {
    fn from_bytes(addr: &[u8]) -> Result<Ipv6Addr> {
        let mut rdr = Cursor::new(addr);
        let a = try!(rdr.read_u16::<BigEndian>());
        let b = try!(rdr.read_u16::<BigEndian>());
        let c = try!(rdr.read_u16::<BigEndian>());
        let d = try!(rdr.read_u16::<BigEndian>());
        let e = try!(rdr.read_u16::<BigEndian>());
        let f = try!(rdr.read_u16::<BigEndian>());
        let g = try!(rdr.read_u16::<BigEndian>());
        let h = try!(rdr.read_u16::<BigEndian>());
        Ok(Ipv6Addr::new(a, b, c, d, e, f, g, h))
    }
}

#[derive(Debug)]
pub struct Ipv4Header {
    pub version: u8,
    pub hlen: usize,
    pub tos: u8,
    pub len: u16,
    pub id: u16,
    pub offset: u16,
    pub ttl: u8,
    pub proto: IpProto,
    chksum: u16,
    pub src: Ipv4Addr,
    pub dest: Ipv4Addr,
}

impl FromBytes for Ipv4Header {
    fn from_bytes(bytes: &[u8]) -> Result<Ipv4Header> {
        let mut rdr = Cursor::new(bytes);
        let v_hl = try!(rdr.read_u8());
        let tos = try!(rdr.read_u8());
        let len = try!(rdr.read_u16::<BigEndian>());
        let id = try!(rdr.read_u16::<LittleEndian>());
        let offset = try!(rdr.read_u16::<LittleEndian>());
        let ttl = try!(rdr.read_u8());
        let proto = IpProto::new(try!(rdr.read_u8()));
        let chksum = try!(rdr.read_u16::<BigEndian>());

        let addr_pos = rdr.position() as usize;
        let src = try!(Ipv4Addr::from_bytes(&bytes[addr_pos..addr_pos+4])); // TODO: Prevent trap
        let dest = try!(Ipv4Addr::from_bytes(&bytes[addr_pos+4..addr_pos+8]));

        Ok(Ipv4Header {
            version: (v_hl >> 4),
            hlen: ((v_hl & 0xF) * 4) as usize,
            tos: tos,
            len: len,
            id: id,
            offset: offset,
            ttl: ttl,
            proto: proto,
            chksum: chksum,
            src: src,
            dest: dest,
        })
    }
}

impl Ipv4Header {
    pub fn pseudo_checksum<T: Iterator<Item=u16>>(&self, length: u16, data_iter: T) -> u16 {
        let src = self.src.octets();
        let dest = self.dest.octets();
        let bytes = [(length >> 8) as u8, length as u8, 
                     0, self.proto.value(),
                     src[0], src[1],
                     src[2], src[3],
                     dest[0], dest[1],
                     dest[2], dest[3]];
        bytes.pair_iter().chain(data_iter).checksum()
    }

    pub fn checksum_valid(&self) -> bool {
        let src = self.src.octets();
        let dest = self.dest.octets();
        let bytes = [((self.version << 4) | (self.hlen / 4) as u8), self.tos,
                     (self.len >> 8) as u8, self.len as u8, 
                     self.id as u8, (self.id >> 8) as u8,
                     self.offset as u8, (self.offset >> 8) as u8,
                     self.ttl, self.proto.value(),
                     src[0], src[1],
                     src[2], src[3],
                     dest[0], dest[1],
                     dest[2], dest[3]];
        (self.chksum == bytes.pair_iter().checksum())
    }
}

#[derive(Debug)]
pub struct Ipv6Header {
    pub version: u8,
    pub class: u8,
    pub flow: u32,
    pub plen: u16,
    pub nexth: IpProto,
    pub hoplim: u8,
    pub src: Ipv6Addr,
    pub dest: Ipv6Addr,
}

impl FromBytes for Ipv6Header {
    fn from_bytes(bytes: &[u8]) -> Result<Ipv6Header> {
        let mut rdr = Cursor::new(bytes);
        let v_tc_fl = try!(rdr.read_u32::<LittleEndian>());
        let plen = try!(rdr.read_u16::<BigEndian>());
        let nexth = IpProto::new(try!(rdr.read_u8()));
        let hoplim = try!(rdr.read_u8());

        let pos = rdr.position() as usize;
        let src = try!(Ipv6Addr::from_bytes(&bytes[pos..pos+16]));
        let dest = try!(Ipv6Addr::from_bytes(&bytes[pos+16..pos+32]));

        Ok(Ipv6Header {
            version: (v_tc_fl >> 28) as u8,
            class: ((v_tc_fl >> 20) & 0xFF) as u8,
            flow: (v_tc_fl & 0xFFFFF),
            plen: plen,
            nexth: nexth,
            hoplim: hoplim,
            src: src,
            dest: dest,
        })
    }
}

impl Ipv6Header {
    pub fn pseudo_checksum<T: Iterator<Item=u16>>(&self, length: u16, data_iter: T) -> u16 {
        let bytes = [(self.version << 4 | self.class >> 4), (self.class << 4 | (self.flow >> 16) as u8),
                     ];
        bytes.pair_iter().chain(data_iter).checksum()
    }
}

#[derive(Debug)]
pub enum IpHeader {
    V4(Ipv4Header),
    V6(Ipv6Header),
}

impl FromBytes for IpHeader {
    fn from_bytes(bytes: &[u8]) -> Result<IpHeader> {
        let mut rdr = Cursor::new(bytes);
        let version = try!(rdr.read_u8()) >> 4;
        match version {
            4 => match Ipv4Header::from_bytes(bytes) {
                Ok(header) => Ok(IpHeader::V4(header)),
                Err(error) => Err(error),
            },
            6 => match Ipv6Header::from_bytes(bytes) {
                Ok(header) => Ok(IpHeader::V6(header)),
                Err(error) => Err(error),
            },
            other => {
                Err(Error::UnsupportedVersion(other))
            },
        }
    }
}

impl IpHeader {
    pub fn pseudo_checksum<T: Iterator<Item=u16>>(&self, length: u16, data_iter: T) -> u16 {
        match self {
            &IpHeader::V4(ref ipv4_hdr) => {
                ipv4_hdr.pseudo_checksum(length, data_iter)
            },
            &IpHeader::V6(ref ipv6_hdr) => {
                ipv6_hdr.pseudo_checksum(length, data_iter)
            }
        }
    }

    pub fn checksum_valid(&self) -> bool {
        match self {
            &IpHeader::V4(ref ipv4_hdr) => {
                ipv4_hdr.checksum_valid()
            },
            &IpHeader::V6(ref ipv6_hdr) => {
                true
            }
        }
    }

    pub fn len(&self) -> usize {
        match self {
            &IpHeader::V4(ref ipv4_hdr) => {
                ipv4_hdr.hlen
            },
            &IpHeader::V6(ref ipv6_hdr) => {
                40
            }
        }
    }

    pub fn proto(&self) -> &IpProto {
        match self {
            &IpHeader::V4(ref ipv4_hdr) => {
                &ipv4_hdr.proto
            },
            &IpHeader::V6(ref ipv6_hdr) => {
                &ipv6_hdr.nexth
            }
        }
    }
}

trait Checksum {
    fn checksum(&mut self) -> u16;
}

impl<T> Checksum for T where T: Iterator<Item=u16> {
    fn checksum(&mut self) -> u16 {
        !self.fold(0, |a, b| {
            let mut folded = (a as u32) + (b as u32);
            while folded > 0xFFFF {
                folded = (folded >> 16) + (folded & 0xFFFF);
            }
            (folded as u16)
        })
    }
}

struct PairIterator<'a> {
    pos: usize,
    bytes: &'a [u8],
}

impl<'a> Iterator for PairIterator<'a> {
    type Item = u16;

    fn next(&mut self) -> Option<u16> {
        let pos = self.pos;
        let len = self.bytes.len();
        self.pos += 2;

        if pos < len {
            Some(((self.bytes[pos] as u16) << 8) + (if pos < len - 1 { self.bytes[pos + 1] as u16 } else { 0 }))
        } else {
            None
        }
    }
}

pub trait Pair {
    fn pair_iter<'a>(&'a self) -> PairIterator<'a>;
}

impl Pair for [u8] {
    fn pair_iter(&self) -> PairIterator {
        PairIterator {
            pos: 0,
            bytes: self,
        }
    }
}
