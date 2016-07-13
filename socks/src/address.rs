use std::str;
use std::net::{SocketAddrV4, SocketAddrV6, Ipv4Addr};
use std::io::{Read, Write};

use version::Version;
use result::{Result, Error};

const SOCKS5_ADDR_TYPE_IPV4: u8 = 0x01;
const SOCKS5_ADDR_TYPE_DOMAIN_NAME: u8 = 0x03;
const SOCKS5_ADDR_TYPE_IPV6: u8 = 0x04;

#[derive(Debug, Clone, PartialEq)]
pub enum Address {
    V4(SocketAddrV4),
    V6(SocketAddrV6),
    HostName(String, u16),
}

impl Address {
    pub fn read_from<R: Read>(stream: &mut R, version: Version) -> Result<Self> {
        match version {
            Version::V4 => {
                let mut buf = Vec::new();
                try!(stream.take(6).read_to_end(&mut buf));
                let port = (buf[1] as u16) << 8 | buf[0] as u16;
                let addr = Ipv4Addr::new(buf[2], buf[3], buf[4], buf[5]);
                Ok(Address::V4(SocketAddrV4::new(addr, port)))
            }
            Version::V5 => {
                let mut type_buf = Vec::new();
                let mut addr_buf = Vec::new();
                try!(stream.take(1).read_to_end(&mut type_buf));
                match type_buf[0] {
                    SOCKS5_ADDR_TYPE_IPV4 => {
                        try!(stream.take(4).read_to_end(&mut addr_buf));
                    }
                    SOCKS5_ADDR_TYPE_IPV6 => {
                        try!(stream.take(16).read_to_end(&mut addr_buf));
                    }
                    SOCKS5_ADDR_TYPE_DOMAIN_NAME => {
                        try!(stream.take(1).read_to_end(&mut type_buf));
                        try!(stream.take(type_buf[1] as u64).read_to_end(&mut addr_buf));
                    }
                    _ => return Err(Error::AddrNotSupported),
                }

                let mut port_buf = Vec::new();
                try!(stream.take(2).read_to_end(&mut port_buf));
                let port = (port_buf[1] as u16) << 8 | port_buf[0] as u16;

                match type_buf[0] {
                    SOCKS5_ADDR_TYPE_IPV4 => {
                        let addr =
                            Ipv4Addr::new(addr_buf[0], addr_buf[1], addr_buf[2], addr_buf[3]);
                        Ok(Address::V4(SocketAddrV4::new(addr, port)))
                    }
                    SOCKS5_ADDR_TYPE_IPV6 => unimplemented!(),
                    SOCKS5_ADDR_TYPE_DOMAIN_NAME => {
                        let host = try!(str::from_utf8(&addr_buf[..])).to_string();
                        Ok(Address::HostName(host, port))
                    }
                    _ => Err(Error::AddrNotSupported),
                }
            }
        }
    }

    pub fn write_to<W: Write>(&self,
                              stream: &mut W,
                              version: Version,
                              user_id: Option<&str>)
                              -> Result<()> {
        match version {
            Version::V4 => {
                let port = match *self {
                    Address::V4(addr) => addr.port(),
                    Address::HostName(ref _host, port) => port,
                    Address::V6(_addr) => return Err(Error::AddrNotSupported),
                };
                try!(stream.write_all(&[(port >> 8) as u8, port as u8]));

                let addr = match *self {
                    Address::V4(addr) => *addr.ip(),
                    Address::HostName(ref _host, _port) => Ipv4Addr::new(0, 0, 0, 255),
                    Address::V6(_addr) => return Err(Error::AddrNotSupported),
                };
                try!(stream.write_all(&addr.octets()));

                match user_id {
                    Some(id) => try!(stream.write_all(id.as_bytes())),
                    None => (),
                }
                try!(stream.write_all(&[0]));

                match *self {
                    Address::V4(_addr) => (),
                    Address::HostName(ref host, _port) => {
                        try!(stream.write_all(host.as_bytes()));
                        try!(stream.write_all(&[0]));
                    }
                    Address::V6(_addr) => return Err(Error::AddrNotSupported),
                }
                Ok(())
            }
            Version::V5 => {
                let port = match *self {
                    Address::V4(addr) => {
                        try!(stream.write_all(&[SOCKS5_ADDR_TYPE_IPV4]));
                        try!(stream.write_all(&addr.ip().octets()));
                        addr.port()
                    }
                    Address::V6(addr) => {
                        try!(stream.write_all(&[SOCKS5_ADDR_TYPE_IPV6]));
                        for seg in addr.ip().segments().iter() {
                            try!(stream.write_all(&[(*seg >> 8) as u8, *seg as u8]));
                        }
                        addr.port()
                    }
                    Address::HostName(ref host, port) => {
                        try!(stream.write_all(&[SOCKS5_ADDR_TYPE_DOMAIN_NAME]));
                        try!(stream.write_all(&[host.len() as u8]));
                        try!(stream.write_all(host.as_bytes()));
                        port
                    }
                };
                try!(stream.write_all(&[(port >> 8) as u8, port as u8]));
                Ok(())
            }
        }
    }
}
