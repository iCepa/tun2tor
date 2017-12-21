extern crate nix;
extern crate tokio_core;
extern crate tun2tor;

use std::net::{SocketAddr, IpAddr, Ipv4Addr};
use tokio_core::reactor::Core;

use tun2tor::{Tun, DnsTcpStack, SocksBackend, DnsPortResolver};
use tun2tor::io::stream_transfer;

fn main() {
    let mut core = Core::new().unwrap();
    let handle = core.handle();

    let utun = Tun::new(&handle).unwrap();
    utun.set_addr(Ipv4Addr::new(172, 30, 20, 1)).unwrap();
    utun.set_netmask(Ipv4Addr::new(255, 255, 255, 255)).unwrap();

    let resolver = DnsPortResolver::new(&SocketAddr::new(
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
        12345,
    ));
    let backend = SocksBackend::new(&SocketAddr::new(
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
        9050,
    ));
    let stack = DnsTcpStack::new(backend, resolver, &handle);

    core.run(stream_transfer(stack, utun)).unwrap();
}
