use std::net::{SocketAddr, IpAddr, Ipv4Addr};
use std::os::raw::c_int;
use std::os::unix::io::FromRawFd;
use tokio_core::reactor::Core;

use super::{DnsTcpStack, DnsPortResolver, Tun, SocksBackend};
use tun::platform;
use io::stream_transfer;

#[no_mangle]
pub unsafe extern "C" fn tun2tor_run(fd: c_int, resolver_port: c_int, socks_port: c_int) {
    let mut core = Core::new().unwrap();
    let handle = core.handle();

    let tun = platform::Tun::from_raw_fd(fd);
    let tun = Tun::from_tun(tun, &handle).unwrap();
    let resolver = DnsPortResolver::new(&SocketAddr::new(
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
        resolver_port as u16,
    ));
    let backend = SocksBackend::new(&SocketAddr::new(
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
        socks_port as u16,
    ));
    let stack = DnsTcpStack::new(backend, resolver, &handle);

    core.run(stream_transfer(stack, tun)).unwrap();
}
