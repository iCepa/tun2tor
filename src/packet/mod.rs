#![forbid(unsafe_code)]

#[macro_use]
mod bytes;
mod ip;
mod udp;
mod tcp;

use std::fmt;
use std::io;
use std::net::SocketAddr;

use tokio_core::io::Window;

use self::bytes::Bytes;
use self::ip::IpHeaderBuilder;
use self::udp::UdpHeaderBuilder;
pub use self::ip::{IpHeader, ExtHeader, IpProto};
pub use self::udp::UdpHeader;
pub use self::tcp::TcpHeader;

#[derive(Debug)]
pub enum Payload {
    Udp(UdpHeader),
    Tcp(TcpHeader),
    Unknown(IpProto),
}

impl Payload {
    pub fn src(&self) -> Option<u16> {
        match self {
            &Payload::Udp(ref u) => Some(u.src()),
            &Payload::Tcp(ref t) => Some(t.src()),
            &Payload::Unknown(..) => None,
        }
    }

    pub fn dest(&self) -> Option<u16> {
        match self {
            &Payload::Udp(ref u) => Some(u.dest()),
            &Payload::Tcp(ref t) => Some(t.dest()),
            &Payload::Unknown(..) => None,
        }
    }

    pub fn is_udp(&self) -> bool {
        if let &Payload::Udp(..) = self {
            true
        } else {
            false
        }
    }
}

pub struct IpPacket {
    pub fixed: IpHeader,
    pub exts: Vec<ExtHeader>,
    pub payload: Payload,
    data: Bytes,
    bytes: Bytes,
}

impl fmt::Debug for IpPacket {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt.debug_struct("IpPacket")
            .field("fixed", &self.fixed)
            .field("exts", &self.exts)
            .field("payload", &self.payload)
            .field("data", &self.data.len())
            .field("bytes", &self.bytes.len())
            .field("checksum_valid", &self.checksum_valid())
            .finish()
    }
}

impl IpPacket {
    pub fn new(bytes: Box<[u8]>) -> io::Result<IpPacket> {
        IpPacket::with_bytes(Bytes::new(bytes))
    }

    fn with_bytes(bytes: Bytes) -> io::Result<IpPacket> {
        let (ip_hdr, mut remaining) = try!(IpHeader::with_bytes(bytes.clone()));
        let mut exts = Vec::new();
        let mut next = ip_hdr.next();
        loop {
            match next {
                IpProto::Udp => {
                    return match UdpHeader::with_bytes(remaining) {
                        Ok((udp_hdr, data)) => {
                            Ok(IpPacket {
                                fixed: ip_hdr,
                                exts: exts,
                                payload: Payload::Udp(udp_hdr),
                                data: data,
                                bytes: bytes,
                            })
                        }
                        Err(e) => Err(e),
                    };
                }
                IpProto::Tcp => {
                    return match TcpHeader::with_bytes(remaining) {
                        Ok((tcp_hdr, data)) => {
                            Ok(IpPacket {
                                fixed: ip_hdr,
                                exts: exts,
                                payload: Payload::Tcp(tcp_hdr),
                                data: data,
                                bytes: bytes,
                            })
                        }
                        Err(e) => Err(e),
                    };
                }
                p => {
                    match ExtHeader::with_bytes(remaining.clone(), p) {
                        Ok((ext_hdr, extra)) => {
                            next = ext_hdr.next();
                            remaining = extra;
                            exts.push(ext_hdr);
                        }
                        Err(ref e) if e.kind() == io::ErrorKind::InvalidData => {
                            return Ok(IpPacket {
                                fixed: ip_hdr,
                                exts: exts,
                                payload: Payload::Unknown(p),
                                data: remaining,
                                bytes: bytes,
                            })
                        }
                        Err(e) => return Err(e),
                    }
                }
            }
        }
    }

    pub fn src(&self) -> Option<SocketAddr> {
        self.payload.src().map(|p| SocketAddr::new(self.fixed.src(), p))
    }

    pub fn dest(&self) -> Option<SocketAddr> {
        self.payload.dest().map(|p| SocketAddr::new(self.fixed.dest(), p))
    }

    pub fn checksum_valid(&self) -> bool {
        if let &IpHeader::V4(ref h) = &self.fixed {
            if !h.checksum_valid() {
                return false;
            }
        }

        let data = self.data.pair_iter();
        match &self.payload {
            &Payload::Udp(ref u) => u.checksum_valid(&self.fixed, data),
            &Payload::Tcp(ref t) => t.checksum_valid(&self.fixed, data),
            &Payload::Unknown(_p) => true,
        }
    }

    pub fn calculate_checksum(&mut self) {
        if let &mut IpHeader::V4(ref mut h) = &mut self.fixed {
            h.calculate_checksum()
        }

        let data = self.data.pair_iter();
        match &mut self.payload {
            &mut Payload::Udp(ref mut u) => u.calculate_checksum(&self.fixed, data),
            // &Payload::Tcp(ref mut t) => t.calculate_checksum(&self.fixed, data),
            _ => (),
        }
    }

    pub fn into_inner(self) -> Box<[u8]> {
        self.into_data().into_inner()
    }

    pub fn into_data(self) -> Window<Box<[u8]>> {
        drop(self.fixed);
        drop(self.payload);
        drop(self.exts);
        drop(self.bytes);
        Bytes::try_unwrap(self.data).unwrap()
    }
}

#[derive(Default, Debug, Clone)]
pub struct UdpPacketBuilder<'a> {
    ip: IpHeaderBuilder,
    udp: UdpHeaderBuilder,
    data: Option<&'a [u8]>,
}

impl<'a> UdpPacketBuilder<'a> {
    pub fn new() -> UdpPacketBuilder<'a> {
        let mut builder = UdpPacketBuilder::default();
        builder.ip = builder.ip.proto(IpProto::Udp);
        builder
    }

    pub fn src(mut self, src: SocketAddr) -> UdpPacketBuilder<'a> {
        self.ip = self.ip.src(src.ip());
        self.udp = self.udp.src(src.port());
        self
    }

    pub fn dest(mut self, dest: SocketAddr) -> UdpPacketBuilder<'a> {
        self.ip = self.ip.dest(dest.ip());
        self.udp = self.udp.dest(dest.port());
        self
    }

    pub fn data(mut self, data: &'a [u8]) -> UdpPacketBuilder<'a> {
        self.data = Some(data);
        self
    }

    pub fn len(&self) -> Option<usize> {
        let ip_len = match self.ip.len() {
            Some(l) => l,
            None => return None,
        };

        let data_len = match self.data.map(|d| d.len()) {
            Some(l) => l,
            None => return None,
        };

        Some(ip_len + UdpHeaderBuilder::len() + data_len)
    }

    pub fn build(self) -> IpPacket {
        let data = self.data.unwrap_or_else(|| unimplemented!());
        let len = self.len().unwrap_or_else(|| unimplemented!());

        let bytes = Bytes::new(vec![0; len].into_boxed_slice());

        let (mut fixed, remaining) = self.ip.build(bytes.clone());
        fixed.set_total_len(len);

        let (mut udp, mut remaining) = self.udp.build(remaining);
        udp.set_data_len(data.len());

        remaining.as_mut().clone_from_slice(data);

        let mut packet = IpPacket {
            fixed: fixed,
            exts: Vec::new(),
            payload: Payload::Udp(udp),
            data: remaining,
            bytes: bytes,
        };

        packet.calculate_checksum();
        packet
    }
}
