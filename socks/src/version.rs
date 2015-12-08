use std::fmt;
use std::io::{Read, Write};

use result::{Result, Error};

const SOCKS4_VERSION: u8 = 0x04;
const SOCKS5_VERSION: u8 = 0x05;

#[derive(PartialEq)]
pub enum Version {
    V4,
    V5,
}

impl fmt::Debug for Version {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Version::V4 => write!(f, "SOCKS4"),
            Version::V5 => write!(f, "SOCKS5"),
        }
    }
}

impl Version {
    pub fn read_from<R: Read + Sized>(stream: &mut R) -> Result<Self> {
        let mut buf = Vec::new();
        try!(stream.take(1).read_to_end(&mut buf));
        match buf[0] {
            SOCKS4_VERSION => Ok(Version::V4),
            SOCKS5_VERSION => Ok(Version::V5),
            _ => Err(Error::SOCKSVersionNotSupported),
        }
    }

    pub fn write_to<W: Write + Sized>(&self, stream: &mut W) -> Result<()> {
        let v = match *self {
            Version::V4 => SOCKS4_VERSION,
            Version::V5 => SOCKS5_VERSION,
        };
        try!(stream.write(&[v]));
        Ok(())
    }
}
