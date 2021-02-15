use std::io;
use std::net::{SocketAddr, IpAddr, Ipv4Addr};

use futures::{self, Future, Stream, Sink, Poll, StartSend};
use lwip::{NetIf, TcpListener, EventedTcpStream};
use tokio_core::net::TcpStream;
use tokio_core::reactor::Handle;

use io::transfer;

pub trait TcpBackend {
    fn build(
        &self,
        addr: &SocketAddr,
        handle: &Handle,
    ) -> Box<dyn Future<Item = TcpStream, Error = io::Error>>;
}

pub struct TcpStack {
    netif: Box<NetIf>,
    backends: Box<dyn Future<Item = (), Error = io::Error>>,
}

impl TcpStack {
    pub fn new<B: 'static + TcpBackend>(backend: B, handle: &Handle) -> TcpStack {
        // FIXME(ahf): While tuning, ensure this set is smaller than LwIP's
        // MEMP_NUM_TCP_PCB(_LISTEN) in lwipopts.h.
        let netif = NetIf::add(
            Ipv4Addr::new(0, 0, 0, 0),
            Ipv4Addr::new(0, 0, 0, 0),
            Ipv4Addr::new(0, 0, 0, 0),
        );

        let handle = handle.clone();
        let listener =
            TcpListener::bind(&SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0)).unwrap();
        let backends = listener.for_each(move |incoming| {
            let dest = incoming.local().unwrap();
            let incoming = EventedTcpStream::new(incoming);
            let stream = backend.build(&dest, &handle).and_then(move |outgoing| {
                transfer(outgoing, incoming)
            });
            handle.spawn(stream.then(|_| futures::finished(())));
            Ok(())
        });

        TcpStack {
            netif: netif,
            backends: Box::new(backends),
        }
    }
}

impl Sink for TcpStack {
    type SinkItem = Box<[u8]>;
    type SinkError = io::Error;

    fn start_send(&mut self, item: Box<[u8]>) -> StartSend<Box<[u8]>, io::Error> {
        self.netif.start_send(item)
    }

    fn poll_complete(&mut self) -> Poll<(), io::Error> {
        self.netif.poll_complete()
    }
}

impl Stream for TcpStack {
    type Item = Box<[u8]>;
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Option<Box<[u8]>>, io::Error> {
        self.backends.poll()?;
        self.netif.poll().map(
            |a| a.map(|o| o.map(|(buf, _addr)| buf)),
        )
    }
}
