extern crate byteorder;

use std::net::{SocketAddr, SocketAddrV4, SocketAddrV6};
use std::io::{self, Read, Write};

use byteorder::{ReadBytesExt, WriteBytesExt, BigEndian};

const SOCKS4_VERSION : u8 = 0x04;
const SOCKS5_VERSION : u8 = 0x05;

const SOCKS_CMD_TCP_CONNECT   : u8 = 0x01;
const SOCKS_CMD_TCP_BIND      : u8 = 0x02;
const SOCKS_CMD_UDP_ASSOCIATE : u8 = 0x03;

const SOCKS5_AUTH_METHOD_NONE     : u8 = 0x00;
const SOCKS5_AUTH_METHOD_GSSAPI   : u8 = 0x01;
const SOCKS5_AUTH_METHOD_PASSWORD : u8 = 0x02;

const SOCKS5_ADDR_TYPE_IPV4        : u8 = 0x01;
const SOCKS5_ADDR_TYPE_DOMAIN_NAME : u8 = 0x03;
const SOCKS5_ADDR_TYPE_IPV6        : u8 = 0x04;

trait ByteEnum {
    fn as_u8(&self) -> u8;
    fn from_u8(code: u8) -> Option<Self>;
}

#[derive(PartialEq)]
pub enum Version {
    Socks4,
    Socks5
}

impl ByteEnum for Version {
    fn as_u8(&self) -> u8 {
        match *self {
            Version::Socks4 => SOCKS4_VERSION,
            Version::Socks5 => SOCKS5_VERSION,
        }
    }

    fn from_u8(code: u8) -> Option<Version> {
        match code {
            SOCKS4_VERSION => Some(Version::Socks4),
            SOCKS5_VERSION => Some(Version::Socks5),
            _ => None,
        }
    }
}

#[derive(PartialEq)]
pub enum Command {
    TcpConnect,
    TcpBind,
    UdpAssociate,
}

impl ByteEnum for Command {
    fn as_u8(&self) -> u8 {
        match *self {
            Command::TcpConnect => SOCKS_CMD_TCP_CONNECT,
            Command::TcpBind => SOCKS_CMD_TCP_BIND,
            Command::UdpAssociate => SOCKS_CMD_UDP_ASSOCIATE,
        }
    }

    fn from_u8(code: u8) -> Option<Command> {
        match code {
            SOCKS_CMD_TCP_CONNECT => Some(Command::TcpConnect),
            SOCKS_CMD_TCP_BIND => Some(Command::TcpBind),
            SOCKS_CMD_UDP_ASSOCIATE => Some(Command::UdpAssociate),
            _ => None,
        }
    }
}

pub enum Address {
    SocketAddress(SocketAddr),
    DomainName(String, u16),
}

trait Writeable {
    fn write_to<W: Write + Sized>(&self, stream: &mut W, version: &Version, user_id: &Option<String>) -> io::Result<()>;
}

impl Writeable for Command {
    fn write_to<W: Write + Sized>(&self, stream: &mut W, version: &Version, user_id: &Option<String>) -> io::Result<()> {
        assert!(*self != Command::UdpAssociate || *version == Version::Socks5);
        try!(stream.write_u8(self.as_u8()));
        Ok(())
    }
}

impl Writeable for Version {
    fn write_to<W: Write + Sized>(&self, stream: &mut W, version: &Version, user_id: &Option<String>) -> io::Result<()> {
        try!(stream.write_u8(self.as_u8()));
        Ok(())
    }
}

impl Writeable for Address {
    fn write_to<W: Write + Sized>(&self, stream: &mut W, version: &Version, user_id: &Option<String>) -> io::Result<()> {
        match self {
            &Address::SocketAddress(addr) => {
                match *version {
                    Version::Socks4 => {
                        match addr {
                            SocketAddr::V4(addr) => {
                                try!(stream.write_u16::<BigEndian>(addr.port()));
                                try!(stream.write_all(&addr.ip().octets()));
                                if user_id.is_some() {
                                    try!(stream.write_all(user_id.as_ref().unwrap().as_bytes()));
                                }       
                                try!(stream.write_u8(0));              
                            },
                            SocketAddr::V6(addr) => {
                                panic!("IPv6 not supported in SOCKS4")
                            }
                        }
                    },
                    Version::Socks5 => {
                        match addr {
                            SocketAddr::V4(addr) => {
                                try!(stream.write_u8(SOCKS5_ADDR_TYPE_IPV4));
                                try!(stream.write_all(&addr.ip().octets()));
                            },
                            SocketAddr::V6(addr) => {
                                try!(stream.write_u8(SOCKS5_ADDR_TYPE_IPV6));
                                for seg in addr.ip().segments().iter() {
                                    try!(stream.write_u16::<BigEndian>(*seg));
                                }
                            }
                        }
                        try!(stream.write_u16::<BigEndian>(addr.port()));
                    }
                }

            },
            &Address::DomainName(ref domain, port) => {
                match *version {
                    Version::Socks4 => {
                        try!(stream.write_u16::<BigEndian>(port));
                        try!(stream.write_all(&[0, 0, 0, 255]));
                        if user_id.is_some() {
                            try!(stream.write_all(user_id.as_ref().unwrap().as_bytes()));
                        }
                        try!(stream.write_u8(0));
                        try!(stream.write_all(domain.as_bytes()));
                        try!(stream.write_u8(0));
                    },
                    Version::Socks5 => {
                        try!(stream.write_u8(SOCKS5_ADDR_TYPE_DOMAIN_NAME));
                        try!(stream.write_u8(domain.len() as u8));
                        try!(stream.write_all(domain.as_bytes()));
                        try!(stream.write_u16::<BigEndian>(port)); 
                    }
                }
            },
        }
        Ok(())
    }
}

struct Request {
    pub version: Version,
    pub command: Command,
    pub address: Address,
    pub user_id: Option<String>,
}

impl Request {
    fn write_to<W: Write + Sized>(&self, stream: &mut W) -> io::Result<()> {
        self.version.write_to(stream, &self.version, &self.user_id);
        self.command.write_to(stream, &self.version, &self.user_id);
        self.address.write_to(stream, &self.version, &self.user_id);
        Ok(())
    }
}
