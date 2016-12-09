use std::io::{self, Read, Write};
use std::net::Ipv4Addr;
use std::os::unix::io::{RawFd, AsRawFd};

use futures::{Async, Stream, Sink, Poll, AsyncSink, StartSend};
use tokio_core::reactor::{Handle, PollEvented};
use nix::libc::{c_char, c_short, sockaddr};

const IFNAMSIZ: usize = 16;

#[repr(C)]
pub struct ifreq_addr {
    pub ifra_name: [c_char; IFNAMSIZ],
    pub ifra_addr: sockaddr,
}

#[repr(C)]
pub struct ifreq_flags {
    pub ifra_name: [c_char; IFNAMSIZ],
    pub ifra_flags: c_short,
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
#[path = "macos.rs"]
pub mod platform;

#[cfg(any(target_os = "linux"))]
#[path = "linux.rs"]
pub mod platform;

pub struct Tun {
    io: PollEvented<platform::Tun>,
}

impl Tun {
    pub fn new(handle: &Handle) -> io::Result<Tun> {
        Tun::from_tun(try!(platform::Tun::new()), handle)
    }

    pub fn from_tun(tun: platform::Tun, handle: &Handle) -> io::Result<Tun> {
        Ok(Tun { io: try!(PollEvented::new(tun, handle)) })
    }

    pub fn ifname(&self) -> io::Result<String> {
        self.io.get_ref().ifname()
    }

    pub fn set_addr(&self, addr: Ipv4Addr) -> io::Result<()> {
        self.io.get_ref().set_addr(addr)
    }

    pub fn set_netmask(&self, addr: Ipv4Addr) -> io::Result<()> {
        self.io.get_ref().set_netmask(addr)
    }

    pub fn addr(&self) -> io::Result<Ipv4Addr> {
        self.io.get_ref().addr()
    }

    pub fn netmask(&self) -> io::Result<Ipv4Addr> {
        self.io.get_ref().netmask()
    }

    pub fn poll_read(&self) -> Async<()> {
        self.io.poll_read()
    }

    pub fn poll_write(&self) -> Async<()> {
        self.io.poll_write()
    }
}

impl AsRawFd for Tun {
    fn as_raw_fd(&self) -> RawFd {
        self.io.get_ref().as_raw_fd()
    }
}

impl Read for Tun {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.io.read(buf)
    }
}

impl Write for Tun {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.io.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.io.flush()
    }
}

impl Stream for Tun {
    type Item = Box<[u8]>;
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Option<Box<[u8]>>, io::Error> {
        match self.io.poll_read() {
            Async::Ready(..) => {
                let mut buf = vec![0; 2048]; // TODO: Use MTU
                let size = try_nb!(self.io.read(&mut buf));
                buf.truncate(size);
                Ok(Async::Ready(Some(buf.into_boxed_slice())))
            }
            Async::NotReady => Ok(Async::NotReady),
        }
    }
}

impl Sink for Tun {
    type SinkItem = Box<[u8]>;
    type SinkError = io::Error;

    fn start_send(&mut self, item: Box<[u8]>) -> StartSend<Box<[u8]>, io::Error> {
        let result = self.io.write(&item[..]);
        match result {
            Ok(0) => {
                Err(io::Error::new(io::ErrorKind::WriteZero,
                                   "failed to write packet to interface"))
            }
            Ok(..) => Ok(AsyncSink::Ready),
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => Ok(AsyncSink::NotReady(item)),
            Err(e) => Err(e),
        }
    }

    fn poll_complete(&mut self) -> Poll<(), io::Error> {
        try_nb!(self.io.flush());
        Ok(Async::Ready(()))
    }
}

fn from_nix_error(err: ::nix::Error) -> io::Error {
    io::Error::from_raw_os_error(err.errno() as i32)
}
