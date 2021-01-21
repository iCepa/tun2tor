extern crate byteorder;
#[macro_use]
extern crate futures;
extern crate libc;
extern crate lwip;
extern crate log;
extern crate mio;
#[macro_use]
extern crate nix;
#[macro_use]
extern crate tokio_core;
extern crate tokio_io;

#[macro_use]
mod packet;
mod socks;
mod tcp;
mod dns;
pub mod io;

pub mod tun;
pub mod ffi;

pub use dns::{DnsStack, DnsResolver, DnsPortResolver};
pub use socks::SocksBackend;
pub use tcp::{TcpStack, TcpBackend};
pub use tun::Tun;

use futures::{Stream, Sink, Poll, StartSend, Async};
use tokio_core::reactor::Handle;

use packet::IpPacket;

pub struct DnsTcpStack {
    tcp: TcpStack,
    dns: DnsStack,
}

impl DnsTcpStack {
    pub fn new<B: 'static + TcpBackend, R: 'static + DnsResolver>(
        backend: B,
        resolver: R,
        handle: &Handle,
    ) -> DnsTcpStack {
        DnsTcpStack {
            tcp: TcpStack::new(backend, handle),
            dns: DnsStack::new(resolver, handle),
        }
    }
}

impl Sink for DnsTcpStack {
    type SinkItem = Box<[u8]>;
    type SinkError = ::std::io::Error;

    fn start_send(&mut self, item: Box<[u8]>) -> StartSend<Box<[u8]>, ::std::io::Error> {
        let packet = IpPacket::new(item).unwrap();
        let is_dns = packet.payload.is_udp() &&
            packet.dest().map(|d| d.port() == 53).unwrap_or(false);
        let item = packet.into_inner();
        if is_dns {
            self.dns.start_send(item)
        } else {
            self.tcp.start_send(item)
        }
    }

    fn poll_complete(&mut self) -> Poll<(), ::std::io::Error> {
        self.tcp.poll_complete()?;
        self.dns.poll_complete()
    }
}

impl Stream for DnsTcpStack {
    type Item = Box<[u8]>;
    type Error = ::std::io::Error;

    fn poll(&mut self) -> Poll<Option<Box<[u8]>>, ::std::io::Error> {
        match self.tcp.poll() {
            Ok(Async::Ready(Some(item))) => Ok(Async::Ready(Some(item))),
            Err(e) => Err(e),
            _ => self.dns.poll(),
        }
    }
}
