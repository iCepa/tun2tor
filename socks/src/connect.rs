use std::io::{Read, Write};

use version::Version;
use command::Command;
use address::Address;
use auth::{AuthMethod, Greeting, Verdict};
use request::Request;
use response::Response;
use result::{Result, Error};

pub trait Connect {
    fn socks_connect(&mut self,
                     version: Version,
                     address: Address,
                     auth: &[AuthMethod])
                     -> Result<Address> {
        self.socks_command(Command::TcpConnect, version, address, auth)
    }

    fn socks_command(&mut self,
                     command: Command,
                     version: Version,
                     address: Address,
                     auth: &[AuthMethod])
                     -> Result<Address>;
}

impl<T> Connect for T where T: Read + Write {
    fn socks_command(&mut self,
                     command: Command,
                     version: Version,
                     address: Address,
                     auth: &[AuthMethod])
                     -> Result<Address> {
        if version == Version::V4 && auth.iter().filter(|&m| *m != AuthMethod::None).count() > 0 {
            return Err(Error::AuthMethodNotSupported);
        }
        match version {
            Version::V4 => (),
            Version::V5 => {
                let greeting = Greeting { methods: auth };
                try!(greeting.write_to(self));

                let verdict = try!(Verdict::read_from(self));
                match verdict.method {
                    AuthMethod::None => (),
                    _ => unimplemented!(),
                }
            }
        }

        let request = Request {
            version: version,
            command: command,
            address: address,
            user_id: None,
        };
        try!(request.write_to(self));

        let response = try!(Response::read_from(self));
        match response.err {
            Some(err) => Err(err),
            None => Ok(response.addr),
        }
    }
}
