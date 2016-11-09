use std::error;
use std::fmt;
use std::result;
use std::sync::mpsc::SendError;

use packet::ip::IpProto;

#[derive(Debug)]
pub enum Error {
    IPVersionNotSupported(u8),
    IPProtoNotSupported(IpProto),
    IPChecksumInvalid,
    TCBSendError(SendError<Box<[u8]>>),
}

impl From<SendError<Box<[u8]>>> for Error {
    fn from(error: SendError<Box<[u8]>>) -> Error {
        Error::TCBSendError(error)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::IPVersionNotSupported(ref v) => write!(f, "IP version {:?} not supported", v),
            Error::IPProtoNotSupported(ref p) => write!(f, "IP protocol {:?} not supported", p),
            Error::IPChecksumInvalid => write!(f, "IP checksum invalid"),
            _ => write!(f, "lol"),
        }
    }
}

impl error::Error for Error {
    fn description(&self) -> &str {
        match *self {
            Error::IPVersionNotSupported(ref _v) => "IP version not supported",
            Error::IPProtoNotSupported(ref _p) => "IP protocol not supported",
            Error::IPChecksumInvalid => "IP checksum invalid",
            _ => "lol",
        }
    }
}

pub type Result<T> = result::Result<T, Error>;
