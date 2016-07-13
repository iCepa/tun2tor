use std::fmt;
use std::io::{Read, Write};

use version::Version;
use result::{Result, Error};

const SOCKS5_AUTH_METHOD_NONE: u8 = 0x00;
const SOCKS5_AUTH_METHOD_GSSAPI: u8 = 0x01;
const SOCKS5_AUTH_METHOD_PASSWORD: u8 = 0x02;

#[derive(Copy, Clone, PartialEq)]
pub enum AuthMethod {
    None,
    GSSAPI,
    Password,
}

impl fmt::Debug for AuthMethod {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            AuthMethod::None => write!(f, "None"),
            AuthMethod::GSSAPI => write!(f, "GSSAPI"),
            AuthMethod::Password => write!(f, "Password"),
        }
    }
}

#[derive(Debug)]
pub struct Greeting<'a> {
    pub methods: &'a [AuthMethod],
}

impl<'a> Greeting<'a> {
    pub fn write_to<W: Write + Sized>(&self, stream: &mut W) -> Result<()> {
        let mut methods = self.methods
            .iter()
            .map(|m| {
                match *m {
                    AuthMethod::None => SOCKS5_AUTH_METHOD_NONE,
                    AuthMethod::GSSAPI => SOCKS5_AUTH_METHOD_GSSAPI,
                    AuthMethod::Password => SOCKS5_AUTH_METHOD_PASSWORD,
                }
            })
            .collect::<Vec<u8>>();
        methods.dedup();
        try!((Version::V5).write_to(stream));
        try!(stream.write_all(&[methods.len() as u8]));
        try!(stream.write_all(&mut methods[..]));
        Ok(())
    }
}

#[derive(Debug)]
#[derive(PartialEq)]
pub struct Verdict {
    pub method: AuthMethod,
}

impl Verdict {
    pub fn read_from<R: Read + Sized>(stream: &mut R) -> Result<Self> {
        if try!(Version::read_from(stream)) != Version::V5 {
            return Err(Error::SOCKSVersionNotSupported);
        }

        let mut buf = Vec::new();
        try!(stream.take(1).read_to_end(&mut buf));
        let method = try!(match buf[0] {
            SOCKS5_AUTH_METHOD_NONE => Ok(AuthMethod::None),
            SOCKS5_AUTH_METHOD_GSSAPI => Ok(AuthMethod::GSSAPI),
            SOCKS5_AUTH_METHOD_PASSWORD => Ok(AuthMethod::Password),
            _ => Err(Error::AuthMethodNotSupported),
        });
        Ok(Verdict { method: method })
    }
}
