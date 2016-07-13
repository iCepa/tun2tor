use std::io::{self, Read, Cursor};
use libc::{ENETUNREACH, EHOSTUNREACH, ECONNREFUSED};

use version::Version;
use address::Address;
use result::{Result, Error};

const SOCKS4_STATUS_GRANTED: u8 = 0x5A;
const SOCKS4_STATUS_FAILED: u8 = 0x5B;
const SOCKS4_STATUS_NOT_RUNNING_IDENTD: u8 = 0x5C;
const SOCKS4_STATUS_INCORRECT_USER_ID: u8 = 0x5D;

const SOCKS5_STATUS_GRANTED: u8 = 0x00;
const SOCKS5_STATUS_FAILED: u8 = 0x01;
const SOCKS5_STATUS_NOT_ALLOWED: u8 = 0x02;
const SOCKS5_STATUS_NETWORK_UNREACHABLE: u8 = 0x03;
const SOCKS5_STATUS_HOST_UNREACHABLE: u8 = 0x04;
const SOCKS5_STATUS_REFUSED: u8 = 0x05;
const SOCKS5_STATUS_TTL_EXPIRED: u8 = 0x06;
const SOCKS5_STATUS_COMMAND_NOT_SUPPORTED: u8 = 0x07;
const SOCKS5_STATUS_ADDRESS_NOT_SUPPORTED: u8 = 0x08;

#[derive(Debug)]
pub struct Response {
    pub version: Version,
    pub addr: Address,
    pub err: Option<Error>,
}

impl Response {
    pub fn read_from<R: Read>(stream: &mut R) -> Result<Self> {
        let mut buf = Vec::new();
        try!(stream.take(1).read_to_end(&mut buf));
        let version = match buf[0] {
            0 => Version::V4,
            v => {
                let buf = [v];
                let mut cursor = Cursor::new(&buf[..]);
                try!(Version::read_from(&mut cursor))
            }
        };

        try!(stream.take(1).read_to_end(&mut buf));
        let err = match version {
            Version::V4 => {
                match buf[1] {
                    SOCKS4_STATUS_GRANTED => None,
                    SOCKS4_STATUS_FAILED => {
                        Some(Error::Io(io::Error::new(io::ErrorKind::Other, "Connection failed")))
                    }
                    SOCKS4_STATUS_NOT_RUNNING_IDENTD => Some(Error::IdentDNotRunning),
                    SOCKS4_STATUS_INCORRECT_USER_ID => Some(Error::IdentDInvalidUserID),
                    _ => return Err(Error::StatusInvalid),
                }
            }
            Version::V5 => {
                match buf[1] {
                    SOCKS5_STATUS_GRANTED => None,
                    SOCKS5_STATUS_FAILED => {
                        Some(Error::Io(io::Error::new(io::ErrorKind::Other, "Connection failed")))
                    }
                    SOCKS5_STATUS_NOT_ALLOWED => {
                        Some(Error::Io(io::Error::new(io::ErrorKind::PermissionDenied,
                                                      "Connection not allowed by ruleset")))
                    }
                    SOCKS5_STATUS_NETWORK_UNREACHABLE => {
                        Some(Error::Io(io::Error::from_raw_os_error(ENETUNREACH)))
                    }
                    SOCKS5_STATUS_HOST_UNREACHABLE => {
                        Some(Error::Io(io::Error::from_raw_os_error(EHOSTUNREACH)))
                    }
                    SOCKS5_STATUS_REFUSED => {
                        Some(Error::Io(io::Error::from_raw_os_error(ECONNREFUSED)))
                    }
                    SOCKS5_STATUS_TTL_EXPIRED => Some(Error::TTLExpired),
                    SOCKS5_STATUS_COMMAND_NOT_SUPPORTED => Some(Error::CommandNotSupported),
                    SOCKS5_STATUS_ADDRESS_NOT_SUPPORTED => Some(Error::AddrNotSupported),
                    _ => return Err(Error::StatusInvalid),
                }
            }
        };

        if version == Version::V5 {
            try!(stream.take(1).read_to_end(&mut buf));
            if buf[2] != 0x00 {
                return Err(Error::ResponseInvalid);
            }
        }

        let addr = try!(Address::read_from(stream, version));

        Ok(Response {
            version: version,
            addr: addr,
            err: err,
        })
    }
}
