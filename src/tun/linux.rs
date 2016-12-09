use std::ffi::CStr;
use std::io::{self, Read, Write};
use std::mem;
use std::os::unix::io::{RawFd, FromRawFd, IntoRawFd, AsRawFd};

use mio::{Evented, Ready, Poll, PollOpt, Token};
use mio::unix::EventedFd;
use nix::fcntl::{open, O_RDWR};
use nix::sys::stat::Mode;
use nix::unistd::{read, write, close};

const TUN_PATH: &'static str = "/dev/net/tun";

const IFF_TUN: i16 = 0x1;
const IFF_NO_PI: i16 = 0x1000;

const IOC_TUN_MAGIC: u8 = 'T' as u8;

const TUN_SET_IFF: u8 = 202;
const TUN_GET_IFF: u8 = 210;

pub struct Tun {
    fd: RawFd,
}

impl Tun {
    pub fn new() -> io::Result<Tun> {
        let mut ifreq: super::ifreq_flags = unsafe { mem::zeroed() };
        ifreq.ifra_flags = IFF_TUN | IFF_NO_PI;

        let fd = try!(open(TUN_PATH, O_RDWR, Mode::empty()));

        ioctl!(set_iff with iow!(IOC_TUN_MAGIC, TUN_SET_IFF, 4));
        try!(unsafe { set_iff(fd, &mut ifreq as *mut _ as *mut u8) });
        Ok(Tun { fd: fd })
    }

    pub fn ifname(&self) -> io::Result<String> {
        let mut ifreq: super::ifreq_flags = unsafe { mem::zeroed() };

        ioctl!(get_iff with ior!(IOC_TUN_MAGIC, TUN_GET_IFF, 4));
        try!(unsafe { get_iff(self.fd, &mut ifreq as *mut _ as *mut u8) });

        Ok(unsafe { CStr::from_ptr(ifreq.ifra_name.as_ptr()).to_str().unwrap().to_string() })
    }
}

impl FromRawFd for Tun {
    unsafe fn from_raw_fd(fd: RawFd) -> Tun {
        Tun { fd: fd }
    }
}

impl IntoRawFd for Tun {
    fn into_raw_fd(self) -> RawFd {
        let fd = self.fd;
        mem::forget(self);
        fd
    }
}

impl AsRawFd for Tun {
    fn as_raw_fd(&self) -> RawFd {
        self.fd
    }
}

impl Evented for Tun {
    fn register(&self,
                poll: &Poll,
                token: Token,
                interest: Ready,
                opts: PollOpt)
                -> io::Result<()> {
        EventedFd(&self.fd).register(poll, token, interest, opts)
    }

    fn reregister(&self,
                  poll: &Poll,
                  token: Token,
                  interest: Ready,
                  opts: PollOpt)
                  -> io::Result<()> {
        EventedFd(&self.fd).reregister(poll, token, interest, opts)
    }

    fn deregister(&self, poll: &Poll) -> io::Result<()> {
        EventedFd(&self.fd).deregister(poll)
    }
}

impl Read for Tun {
    fn read(&mut self, dst: &mut [u8]) -> io::Result<usize> {
        <&Tun as Read>::read(&mut &*self, dst)
    }
}

impl<'a> Read for &'a Tun {
    fn read(&mut self, dst: &mut [u8]) -> io::Result<usize> {
        read(self.fd, dst).map_err(super::from_nix_error)
    }
}

impl Write for Tun {
    fn write(&mut self, src: &[u8]) -> io::Result<usize> {
        <&Tun as Write>::write(&mut &*self, src)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<'a> Write for &'a Tun {
    fn write(&mut self, src: &[u8]) -> io::Result<usize> {
        write(self.fd, src).map_err(super::from_nix_error)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Drop for Tun {
    fn drop(&mut self) {
        let _ = close(self.fd);
    }
}
