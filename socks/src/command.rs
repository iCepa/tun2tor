use std::fmt;
use std::io::Write;

use version::Version;
use result::{Result, Error};

const SOCKS_CMD_TCP_CONNECT: u8 = 0x01;
const SOCKS_CMD_TCP_BIND: u8 = 0x02;
const SOCKS_CMD_UDP_ASSOCIATE: u8 = 0x03;

const SOCKS_TOR_CMD_RESOLVE: u8 = 0xF0;
const SOCKS_TOR_CMD_RESOLVE_PTR: u8 = 0xF1;

#[derive(PartialEq)]
#[allow(dead_code)]
pub enum Command {
    TcpConnect,
    TcpBind,
    UdpAssociate,
    TorResolve,
    TorResolvePtr,
}

impl fmt::Debug for Command {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Command::TcpConnect => write!(f, "TCP Connect"),
            Command::TcpBind => write!(f, "TCP Bind"),
            Command::UdpAssociate => write!(f, "UDP Associate"),
            Command::TorResolve => write!(f, "Tor Resolve"),
            Command::TorResolvePtr => write!(f, "Tor Resolve PTR"),
        }
    }
}

impl Command {
    pub fn write_to<W: Write + Sized>(&self, stream: &mut W, version: &Version) -> Result<()> {
        if *version == Version::V4 && *self == Command::UdpAssociate {
            return Err(Error::CommandNotSupported);
        }
        let v = match *self {
            Command::TcpConnect => SOCKS_CMD_TCP_CONNECT,
            Command::TcpBind => SOCKS_CMD_TCP_BIND,
            Command::UdpAssociate => SOCKS_CMD_UDP_ASSOCIATE,
            Command::TorResolve => SOCKS_TOR_CMD_RESOLVE,
            Command::TorResolvePtr => SOCKS_TOR_CMD_RESOLVE_PTR,
        };
        try!(stream.write(&[v]));
        Ok(())
    }
}
