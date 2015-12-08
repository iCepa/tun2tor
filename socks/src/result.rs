use std::fmt;
use std::str;
use std::result;
use std::error;
use std::io;

pub type Result<T> = result::Result<T, Error>;

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    Utf8(str::Utf8Error),
    SOCKSVersionNotSupported,
    CommandNotSupported,
    AddrNotSupported,
    AuthMethodNotSupported,
    ResponseInvalid,
    StatusInvalid,
    TTLExpired,
    IdentDNotRunning,
    IdentDInvalidUserID,
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Error {
        Error::Io(err)
    }
}

impl From<str::Utf8Error> for Error {
    fn from(err: str::Utf8Error) -> Error {
        Error::Utf8(err)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::Io(ref err) => err.fmt(f),
            Error::Utf8(ref err) => err.fmt(f),
            Error::SOCKSVersionNotSupported => write!(f, "Unknown SOCKS version"),
            Error::CommandNotSupported => write!(f, "Command is not supported by SOCKS version"),
            Error::AddrNotSupported => write!(f, "Address is not supported by SOCKS version"),
            Error::AuthMethodNotSupported =>
                write!(f,
                       "Auth method is not supported by SOCKS version or SOCKS server"),
            Error::ResponseInvalid => write!(f, "The response returned from the server is invalid"),
            Error::StatusInvalid => write!(f, "The status returned from the server is invalid"),
            Error::TTLExpired => write!(f, "The TTL expired in transit"),
            Error::IdentDNotRunning =>
                write!(f, "The SOCKS server cannot connect to identd on the client"),
            Error::IdentDInvalidUserID =>
                write!(f, "The client program and identd report different user-ids"),
        }
    }
}

impl error::Error for Error {
    fn description(&self) -> &str {
        match *self {
            Error::Io(ref err) => err.description(),
            Error::Utf8(ref err) => err.description(),
            Error::SOCKSVersionNotSupported => "Unknown SOCKS version",
            Error::CommandNotSupported => "Command is not supported by SOCKS version",
            Error::AddrNotSupported => "Address is not supported by SOCKS version",
            Error::AuthMethodNotSupported =>
                "Auth method is not supported by SOCKS version or SOCKS server",
            Error::ResponseInvalid => "The response returned from the server is invalid",
            Error::StatusInvalid => "The status returned from the server is invalid",
            Error::TTLExpired => "The TTL expired in transit",
            Error::IdentDNotRunning => "The SOCKS server cannot connect to identd on the client",
            Error::IdentDInvalidUserID => "The client program and identd report different user-ids",
        }
    }
}
