#![forbid(unsafe_code)]

mod util;
pub mod result;
pub mod ip;
pub mod udp;
pub mod tcp;

use std::io::Write;
use std::net::{IpAddr, SocketAddr};

use self::result::{Result, Error};
use self::ip::{IpHeader, IpHeaderMut, ExtHeader, IpProto};
use self::udp::{UdpHeader, UdpHeaderMut};
use self::tcp::{TcpHeader, TcpHeaderMut};

pub use self::util::Pair;

#[derive(Debug)]
pub enum Payload<'a> {
    Udp(UdpHeader<'a>),
    Tcp(TcpHeader<'a>),
    Unknown(IpProto),
}

#[derive(Debug)]
pub struct IpPacket<'a> {
    buf: &'a [u8],
    pub fixed: IpHeader<'a>,
    pub exts: Vec<ExtHeader<'a>>,
    pub payload: Payload<'a>,
}

impl<'a> IpPacket<'a> {
    pub fn with_buf<T: AsRef<[u8]>>(buf: &T) -> Result<IpPacket> {
        let buf = buf.as_ref();
        let ip_hdr = try!(IpHeader::with_buf(buf));
        let mut exts = Vec::new();
        let mut next = ip_hdr.next();
        let mut slice = &buf[ip_hdr.len()..];
        loop {
            match next {
                IpProto::Udp => {
                    return Ok(IpPacket {
                        buf: buf,
                        fixed: ip_hdr,
                        exts: exts,
                        payload: Payload::Udp(UdpHeader::with_buf(slice)),
                    })
                }
                IpProto::Tcp => {
                    return Ok(IpPacket {
                        buf: buf,
                        fixed: ip_hdr,
                        exts: exts,
                        payload: Payload::Tcp(TcpHeader::with_buf(slice)),
                    })
                }
                p => {
                    match ExtHeader::with_buf(slice, p) {
                        Ok(ext_hdr) => {
                            next = ext_hdr.next();
                            slice = &slice[ext_hdr.len()..];
                            exts.push(ext_hdr);
                        }
                        Err(Error::IPProtoNotSupported(p)) => {
                            return Ok(IpPacket {
                                buf: buf,
                                fixed: ip_hdr,
                                exts: exts,
                                payload: Payload::Unknown(p),
                            })
                        }
                        Err(e) => return Err(e),
                    }
                }
            }
        }
    }

    pub fn data(&self) -> &[u8] {
        let ip_len = self.fixed.len();
        let ext_len: usize = self.exts.iter().map(|x| x.len()).sum();
        let payload = &self.buf[ip_len + ext_len..];
        match &self.payload {
            &Payload::Udp(ref u) => &payload[UdpHeader::len()..][..u.data_len()],
            &Payload::Tcp(ref t) => &payload[t.len()..self.fixed.total_len() - ip_len - ext_len],
            &Payload::Unknown(_p) => payload,
        }
    }

    pub fn checksum_valid(&self) -> bool {
        if let &IpHeader::V4(ref h) = &self.fixed {
            if !h.checksum_valid() {
                return false;
            }
        }

        let data = self.data().pair_iter();
        match &self.payload {
            &Payload::Udp(ref u) => u.checksum_valid(&self.fixed, data),
            &Payload::Tcp(ref t) => t.checksum_valid(&self.fixed, data),
            &Payload::Unknown(_p) => true,
        }
    }
}

#[derive(Debug)]
pub struct IpPacketMut {
    buf: Vec<u8>,
}

impl IpPacketMut {
    pub fn new(src: IpAddr, dest: IpAddr, next: IpProto) -> IpPacketMut {
        let mut buf = vec![0; 60];
        {
            let mut ip_hdr = IpHeaderMut::new(&mut buf[..], src);
            ip_hdr.set_src(src);
            ip_hdr.set_dest(dest);
            ip_hdr.set_next(next);
        }
        IpPacketMut { buf: buf }
    }

    pub fn new_tcp(src: SocketAddr,
                   dest: SocketAddr,
                   seq_num: u32,
                   ack_num: u32,
                   is_ack: bool,
                   is_syn: bool,
                   data: &[u8])
                   -> IpPacketMut {
        let mut packet = IpPacketMut::new(src.ip(), dest.ip(), IpProto::Tcp);

        let ip_len = {
            IpHeader::with_buf(&packet.buf[..]).unwrap().len()
        };

        {
            let mut tcp_hdr = TcpHeaderMut::new(&mut packet.buf[ip_len..]);
            tcp_hdr.set_src(src.port());
            tcp_hdr.set_dest(dest.port());
            tcp_hdr.set_seq_num(seq_num);
            tcp_hdr.set_ack_num(ack_num);
            tcp_hdr.set_ack(is_ack);
            tcp_hdr.set_syn(is_syn);
        }

        let tcp_len = {
            TcpHeader::with_buf(&packet.buf[ip_len..]).len()
        };

        let total_len = ip_len + tcp_len + data.len();

        packet.buf.resize(total_len, 0);
        (&mut packet.buf[ip_len + tcp_len..]).write_all(data).unwrap();

        {
            let mut ip_hdr = IpHeaderMut::with_buf(&mut packet.buf[..]).unwrap();
            ip_hdr.set_total_len(total_len);
            ip_hdr.calculate_checksum();
        }
        let checksum = {
            let ip_hdr = IpHeader::with_buf(&packet.buf[..]).unwrap();
            let tcp_hdr = TcpHeader::with_buf(&packet.buf[ip_len..]);
            tcp_hdr.calculate_checksum(&ip_hdr,
                                       (&packet.buf[ip_len + tcp_len..total_len]).pair_iter())
        };
        TcpHeaderMut::with_buf(&mut packet.buf[ip_len..]).set_checksum(checksum);

        packet
    }

    pub fn new_udp(src: SocketAddr, dest: SocketAddr, data: &[u8]) -> IpPacketMut {
        let mut packet = IpPacketMut::new(src.ip(), dest.ip(), IpProto::Udp);

        let ip_len = {
            IpHeader::with_buf(&packet.buf[..]).unwrap().len()
        };

        {
            let mut udp_hdr = UdpHeaderMut::with_buf(&mut packet.buf[ip_len..]);
            udp_hdr.set_src(src.port());
            udp_hdr.set_dest(dest.port());
        }

        let udp_len = UdpHeader::len();

        let total_len = ip_len + udp_len + data.len();

        packet.buf.resize(total_len, 0);
        (&mut packet.buf[ip_len + udp_len..]).write_all(data).unwrap();

        {
            let mut ip_hdr = IpHeaderMut::with_buf(&mut packet.buf[..]).unwrap();
            ip_hdr.set_total_len(total_len);
            ip_hdr.calculate_checksum();
        }
        {
            let mut udp_hdr = UdpHeaderMut::with_buf(&mut packet.buf[ip_len..]);
            udp_hdr.set_udp_len(udp_len + data.len());
        }
        let checksum = {
            let ip_hdr = IpHeader::with_buf(&packet.buf[..]).unwrap();
            let udp_hdr = UdpHeader::with_buf(&packet.buf[ip_len..]);
            udp_hdr.calculate_checksum(&ip_hdr,
                                       (&packet.buf[ip_len + udp_len..total_len]).pair_iter())
        };
        UdpHeaderMut::with_buf(&mut packet.buf[ip_len..]).set_checksum(checksum);

        packet
    }

    pub fn into_buf(self) -> Vec<u8> {
        self.buf
    }
}
