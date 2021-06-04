use std::ffi::CStr;
use std::io::{self, Read, Write};
use std::mem;
use std::net::{SocketAddr, IpAddr, Ipv4Addr};
use std::os::unix::io::{RawFd, FromRawFd, IntoRawFd, AsRawFd};
use std::ptr;

use byteorder::{ByteOrder, NetworkEndian};
use mio::{Evented, Ready, Poll, PollOpt, Token};
use mio::unix::EventedFd;
use nix::libc::{getsockopt, socklen_t, c_void, c_int};
use nix::sys::socket::{self, SockAddr, InetAddr, sockaddr, sockaddr_in, socket, connect, SockType,
                       AddressFamily, SockFlag, SOCK_NONBLOCK, SOCK_CLOEXEC, SYSPROTO_CONTROL,
                       AF_INET, AF_INET6};
use nix::sys::uio::{readv, writev, IoVec};
use nix::unistd::close;

const IOC_IF_MAGIC: u8 = 'i' as u8;

const IOC_SET_IFADDR: u8 = 12;
const IOC_SET_IFNETMASK: u8 = 22;
const IOC_GET_IFADDR: u8 = 33;
const IOC_GET_IFNETMASK: u8 = 37;

const UTUN_OPT_IFNAME: c_int = 2;

macro_rules! ifreq_prop {
    ($get:ident, $set:ident, $ioctl_get:ident, $ioctl_set:ident) => {
        pub fn $set(&self, addr: Ipv4Addr) -> io::Result<()> {
            let ifname = self.ifname()?;
            
            let addr_in = match InetAddr::from_std(&SocketAddr::new(IpAddr::V4(addr), 0)) {
                InetAddr::V4(addr_in) => addr_in,
                _ => unreachable!()
            };
            let mut ifra_addr: sockaddr = unsafe { mem::zeroed() };
            unsafe { ptr::copy_nonoverlapping(&addr_in, &mut ifra_addr as *mut _ as *mut sockaddr_in, 1); }

            let mut ifreq: super::ifreq_addr = unsafe { mem::zeroed() };
            unsafe { ptr::copy_nonoverlapping(ifname.as_ptr() as *const _, ifreq.ifra_name.as_mut_ptr(), ifname.len()) };
            ifreq.ifra_addr = ifra_addr;

            ioctl!(write_ptr set_addr with IOC_IF_MAGIC, $ioctl_set; super::ifreq_addr);
            let fd = try_nix!(socket(AddressFamily::Inet, SockType::Datagram, SockFlag::empty(), 0));
            try_nix!(unsafe { set_addr(fd, &ifreq) });
            try_nix!(close(fd));
            Ok(())
        }

        pub fn $get(&self) -> io::Result<Ipv4Addr> {
            let ifname = self.ifname()?;

            let mut ifreq: super::ifreq_addr = unsafe { mem::zeroed() };
            unsafe { ptr::copy_nonoverlapping(ifname.as_ptr() as *const _, ifreq.ifra_name.as_mut_ptr(), ifname.len()) };
            ifreq.ifra_addr.sa_family = AF_INET as u8;

            ioctl!(write_ptr get_addr with IOC_IF_MAGIC, $ioctl_get; super::ifreq_addr);
            let fd = try_nix!(socket(AddressFamily::Inet, SockType::Datagram, SockFlag::empty(), 0));
            try_nix!(unsafe { get_addr(fd, &ifreq) });
            try_nix!(close(fd));

            let addr = match InetAddr::V4(unsafe { *(&ifreq.ifra_addr as *const _ as *const sockaddr_in) }).ip() {
                socket::IpAddr::V4(addr) => addr,
                _ => unreachable!()
            };
            Ok(addr.to_std())
        }
    };
}

pub struct Tun {
    fd: RawFd,
}

impl Tun {
    pub fn new() -> io::Result<Tun> {
        let fd = try_nix!(socket(
            AddressFamily::System,
            SockType::Datagram,
            SOCK_NONBLOCK | SOCK_CLOEXEC,
            SYSPROTO_CONTROL,
        ));
        let ctrl_addr = try_nix!(SockAddr::new_sys_control(
            fd,
            "com.apple.net.utun_control",
            0,
        ));
        try_nix!(connect(fd, &ctrl_addr));
        Ok(Tun { fd })
    }

    pub fn ifname(&self) -> io::Result<String> {
        let mut buf = [0; super::IFNAMSIZ];
        let mut len = buf.len() as socklen_t;
        let success = unsafe {
            getsockopt(
                self.fd,
                SYSPROTO_CONTROL,
                UTUN_OPT_IFNAME,
                buf.as_mut_ptr() as *mut c_void,
                &mut len,
            )
        };
        if success != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(unsafe {
            CStr::from_ptr(buf.as_ptr()).to_str().unwrap().to_string()
        })
    }

    ifreq_prop!(addr, set_addr, IOC_GET_IFADDR, IOC_SET_IFADDR);
    ifreq_prop!(netmask, set_netmask, IOC_GET_IFNETMASK, IOC_SET_IFNETMASK);
}

impl FromRawFd for Tun {
    unsafe fn from_raw_fd(fd: RawFd) -> Tun {
        Tun { fd }
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
    fn register(
        &self,
        poll: &Poll,
        token: Token,
        interest: Ready,
        opts: PollOpt,
    ) -> io::Result<()> {
        EventedFd(&self.fd).register(poll, token, interest, opts)
    }

    fn reregister(
        &self,
        poll: &Poll,
        token: Token,
        interest: Ready,
        opts: PollOpt,
    ) -> io::Result<()> {
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
        let mut buf = [0; 4];
        let len = buf.len();
        let mut iov = [IoVec::from_mut_slice(&mut buf), IoVec::from_mut_slice(dst)];

        readv(self.fd, &mut iov)
            .map(|l| if l > len { l - len } else { 0 })
            .map_err(super::from_nix_error)
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
        if src.len() == 0 {
            return Ok(0);
        }

        let proto = match src[0] >> 4 {
            4 => AF_INET,
            6 => AF_INET6,
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "Invalid IP version",
                ))
            }
        };

        let mut buf = [0; 4];
        let len = buf.len();
        NetworkEndian::write_i32(&mut buf, proto);

        writev(self.fd, &[IoVec::from_slice(&buf), IoVec::from_slice(src)])
            .map(|l| if l > len { l - len } else { 0 })
            .map_err(super::from_nix_error)
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
