use std::io::Write;

use version::Version;
use command::Command;
use address::Address;
use result::Result;

#[derive(Debug, Clone, PartialEq)]
pub struct Request<'a> {
    pub version: Version,
    pub command: Command,
    pub address: Address,
    pub user_id: Option<&'a str>,
}

impl<'a> Request<'a> {
    pub fn write_to<W: Write>(&self, stream: &mut W) -> Result<()> {
        try!(self.version.write_to(stream));
        try!(self.command.write_to(stream, self.version));
        if self.version == Version::V5 {
            try!(stream.write_all(&[0]));
        }
        try!(self.address.write_to(stream, self.version, self.user_id));
        Ok(())
    }
}
