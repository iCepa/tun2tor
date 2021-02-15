use std::io;
use std::net::{SocketAddr, IpAddr, Ipv4Addr};

use futures::{Future, Stream, Sink, StartSend, Poll, Async, AsyncSink};
use tokio_core::net::UdpSocket;
use tokio_core::reactor::Handle;

use packet::{IpPacket, UdpPacketBuilder};

pub trait DnsResolver {
    fn resolve(
        &self,
        query: Box<[u8]>,
        handle: &Handle,
    ) -> Box<dyn Future<Item = Box<[u8]>, Error = io::Error>>;
}

#[derive(Debug, Copy, Clone)]
pub struct DnsPortResolver {
    addr: SocketAddr,
}

impl DnsPortResolver {
    pub fn new(addr: &SocketAddr) -> DnsPortResolver {
        DnsPortResolver { addr: *addr }
    }
}

impl DnsResolver for DnsPortResolver {
    fn resolve(
        &self,
        query: Box<[u8]>,
        handle: &Handle,
    ) -> Box<dyn Future<Item = Box<[u8]>, Error = io::Error>> {
        let addr = self.addr;
        let packet = IpPacket::new(query).unwrap();
        let (src, dest) = (packet.src().unwrap(), packet.dest().unwrap());
        assert_eq!(dest.port(), 53);

        let bind = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 0); // TODO: IPv6
        let socket = UdpSocket::bind(&bind, handle).unwrap();
        Box::new(socket.send_dgram(packet.into_data(), addr).and_then(
            move |(socket, _buf)| {
                let buf = vec![0; 2048]; // FIXME(ahf) on 15/02/2020: MTU isn't really an issue
                                         // here. The buffer size is fine because we only work on localhost.
                socket.recv_dgram(buf).and_then(
                    move |(_socket, buf, len, from)| {
                        if from != addr {
                            return Err(io::Error::new(
                                io::ErrorKind::Other,
                                "invalid DNS reply addess",
                            ));
                        }
                        let response = UdpPacketBuilder::new()
                            .dest(src)
                            .src(dest)
                            .data(&buf[..len])
                            .build()
                            .into_inner();
                        Ok(response)
                    },
                )
            },
        ))
    }
}

pub struct DnsStack {
    handle: Handle,
    resolver: Box<dyn DnsResolver>,
    futures: Vec<Box<dyn Future<Item = Box<[u8]>, Error = io::Error>>>,
}

impl DnsStack {
    pub fn new<R: 'static + DnsResolver>(resolver: R, handle: &Handle) -> DnsStack {
        DnsStack {
            handle: handle.clone(),
            resolver: Box::new(resolver),
            futures: Vec::new(),
        }
    }
}

impl Sink for DnsStack {
    type SinkItem = Box<[u8]>;
    type SinkError = io::Error;

    fn start_send(&mut self, item: Box<[u8]>) -> StartSend<Box<[u8]>, io::Error> {
        // TODO: Limit concurrency
        // TODO: Timeout
        self.futures.push(self.resolver.resolve(item, &self.handle));
        Ok(AsyncSink::Ready)
    }

    fn poll_complete(&mut self) -> Poll<(), io::Error> {
        Ok(Async::Ready(()))
    }
}

impl Stream for DnsStack {
    type Item = Box<[u8]>;
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Option<Box<[u8]>>, io::Error> {
        let mut idx = 0;
        loop {
            if idx >= self.futures.len() {
                return Ok(Async::NotReady);
            }

            let result = match self.futures[idx].poll() {
                Ok(Async::Ready(item)) => Ok(Async::Ready(Some(item))),
                Err(e) => Err(e),
                Ok(Async::NotReady) => {
                    idx += 1;
                    continue;
                }
            };
            self.futures.swap_remove(idx);
            return result;
        }
    }
}
