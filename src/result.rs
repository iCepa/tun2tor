use std::fmt;
use std::result;
use std::error;

use ip::IpProto;

#[derive(Debug)]
pub enum Error {
    IPVersionNotSupported(u8),
    IPProtoNotSupported(IpProto),
    IPChecksumInvalid,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::IPVersionNotSupported(ref v) => write!(f, "IP version {:?} not supported", v),
            Error::IPProtoNotSupported(ref p) => write!(f, "IP protocol {:?} not supported", p),
            Error::IPChecksumInvalid => write!(f, "IP checksum invalid"),
        }
    }
}

impl error::Error for Error {
    fn description(&self) -> &str {
        match *self {
            Error::IPVersionNotSupported(ref _v) => "IP version not supported",
            Error::IPProtoNotSupported(ref _p) => "IP protocol not supported",
            Error::IPChecksumInvalid => "IP checksum invalid",
        }
    }
}

pub type Result<T> = result::Result<T, Error>;

#[macro_export]
macro_rules! try_log {
    ($expr:expr) => (match $expr {
        Ok(val) => val,
        Err(err) => {
            println!("Error: {:}", err);
            return;
        }
    })
}
